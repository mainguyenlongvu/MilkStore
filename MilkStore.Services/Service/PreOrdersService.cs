using AutoMapper;
using Microsoft.EntityFrameworkCore;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.Contract.Repositories.Interface;
using MilkStore.Contract.Services.Interface;
using MilkStore.Core.Utils;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.Repositories.Context;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace MilkStore.Services.Service
{
    public class PreOrdersService : IPreOrdersService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly DatabaseContext _context;
        private readonly IMapper _mapper;
        public PreOrdersService(DatabaseContext context, IUnitOfWork unitOfWork, IMapper mapper)
        {
            _context = context;
            _unitOfWork = unitOfWork;
            _mapper = mapper;
        }

        public async Task<PreOrders> CreatePreOrders(PreOrdersModelView preOrdersModel)
        {
            //var newPreOrder = new PreOrders
            //{
            //    ProductID = preOrdersModel.ProductID,
            //    UserID = preOrdersModel.UserID,
            //    PreoderDate = preOrdersModel.PreoderDate,
            //    Status = preOrdersModel.Status,
            //    Quantity = preOrdersModel.Quantity,
            //};
            PreOrders newPreOrder = _mapper.Map<PreOrders>(preOrdersModel);
            newPreOrder.CreatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<PreOrders>().InsertAsync(newPreOrder);
            await _unitOfWork.SaveAsync();
            return newPreOrder;
        }

        public async Task DeletePreOrders(string id)
        {
            PreOrders preord = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id);
            if (preord == null)
            {
                throw new KeyNotFoundException($"Pre-order with ID {id} was not found.");
            }
            preord.DeletedTime = CoreHelper.SystemTimeNow;
            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preord);
            await _unitOfWork.SaveAsync();
        }

        public async Task<IEnumerable<PreOrders>> GetPreOrders(string? id, int page, int pageSize)
        {
            if (id == null)
            {
                var query = _unitOfWork.GetRepository<PreOrders>()
                    .Entities
                    .Where(detail => detail.DeletedTime == null)
                    .OrderBy(detail => detail.ProductID);


                var paginated = await _unitOfWork.GetRepository<PreOrders>()
                .GetPagging(query, page, pageSize);

                return paginated.Items;

            }
            else
            {
                var preord = await _unitOfWork.GetRepository<PreOrders>()
                    .Entities
                    .FirstOrDefaultAsync(r => r.Id == id && r.DeletedTime == null);
                if (preord == null)
                {
                    throw new KeyNotFoundException($"Pre-order have ID: {id} was not found.");
                }
                return _mapper.Map<List<PreOrders>>(preord);
            }
        }

        public async Task<PreOrders> UpdatePreOrders(string id, PreOrdersModelView preOrdersModel)
        {

            PreOrders preord = await _unitOfWork.GetRepository<PreOrders>().GetByIdAsync(id);

            if (preord == null)
            {
                throw new Exception("Pre-order không tồn tại.");
            }

            //preord.ProductID = preOrdersModel.ProductID;
            //preord.UserID = preOrdersModel.UserID;
            //preord.PreoderDate = preOrdersModel.PreoderDate;
            //preord.Status = preOrdersModel.Status;
            //preord.Quantity = preOrdersModel.Quantity;
            _mapper.Map(preOrdersModel, preord);
            preord.LastUpdatedTime = DateTime.UtcNow;
            await _unitOfWork.GetRepository<PreOrders>().UpdateAsync(preord);
            await _unitOfWork.SaveAsync();
            return preord;
        }
    }
}
