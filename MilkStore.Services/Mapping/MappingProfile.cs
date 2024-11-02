using AutoMapper;
using MilkStore.Contract.Repositories.Entity;
using MilkStore.ModelViews.ResponseDTO;
using MilkStore.ModelViews.OrderModelViews;
using MilkStore.ModelViews.ProductsModelViews;
using MilkStore.ModelViews.UserModelViews;
using MilkStore.Repositories.Entity;
using MilkStore.ModelViews.OrderDetailsModelView;
using MilkStore.ModelViews.CategoryModelViews;
using MilkStore.ModelViews.ReviewsModelView;
using MilkStore.ModelViews.PreOrdersModelView;
using MilkStore.ModelViews.PostModelViews;
using MilkStore.ModelViews.VoucherModelViews;
using MilkStore.ModelViews.GiftModelViews;
using MilkStore.ModelViews.OrderGiftModelViews;
using MilkStore.ModelViews.AuthModelViews;
using MilkStore.ModelViews.OrderDetailGiftModelView;
using MilkStore.ModelViews.RoleModelView;


namespace MilkStore.Services.Mapping
{

    public class MappingProfile : Profile
    {
        public MappingProfile()
        {
            CreateMap<UserUpdateByAdminModel, ApplicationUser>()
                .ForMember(x => x.PasswordHash, option => option.Ignore());


            CreateMap<ApplicationUser, UserProfileResponseModelView>().ReverseMap();

            CreateMap<ApplicationUser, RegisterModelView>().ReverseMap();

            CreateMap<OrderDetailGiftModel, OrderDetailGift>();
            CreateMap<OrderDetailGift, OrderDetailGiftResponseDTO>();
            CreateMap<GiftModel, Gift>();
            CreateMap<Gift, GiftResponseDTO>();
            CreateMap<OrderGiftModel, OrderGift>();
            CreateMap<OrderGift, OrderGiftResponseDTO>();

            CreateMap<CategoryModel, Category>();
            CreateMap<Category, CategoryResponseDTO>();

            #region Post
            CreateMap<PostModelView, Post>();
            CreateMap<Post, PostResponseDTO>()
                .ForMember(dest => dest.Products, opt => opt.MapFrom(src => src.PostProducts.Select(pp => new ProductResponseDTO
                {
                    Id = pp.Product.Id,
                    ProductName = pp.Product.ProductName,
                    Description = pp.Product.Description,
                    Price = pp.Product.Price,
                    QuantityInStock = pp.Product.QuantityInStock,
                    ImageUrl = pp.Product.ImageUrl,
                    CategoryId = pp.Product.CategoryId
                }).ToList()));
            #endregion

            CreateMap<ProductsModel, Products>();
            CreateMap<Products, ProductResponseDTO>();
            CreateMap<UserModelView, ApplicationUser>()
            .ForMember(dest => dest.Points, opt => opt.MapFrom(src => 0)) // Set Points to 0
            .ForMember(dest => dest.CreatedTime, opt => opt.MapFrom(src => DateTimeOffset.UtcNow));

            CreateMap<UserModelView, ApplicationUser>()
            .ForMember(dest => dest.LastUpdatedBy, opt => opt.Ignore())
            .ForMember(dest => dest.LastUpdatedTime, opt => opt.Ignore())
            .ForMember(dest => dest.Points, opt => opt.Ignore()); // Nếu không muốn ánh xạ Points

            CreateMap<ApplicationRole, RoleViewModel>()
            .ForMember(dest => dest.RoleId, opt => opt.MapFrom(src => src.Id))
            .ForMember(dest => dest.RoleName, opt => opt.MapFrom(src => src.Name));
            CreateMap<UserUpdateModelView, ApplicationUser>().ReverseMap();

            CreateMap<Order, OrderModelView>().ReverseMap();
            CreateMap<Order, OrderResponseDTO>()
                .ForMember(dest => dest.OrderDetailss, opt => opt.MapFrom(src => src.OrderDetailss));
                //.ForMember(dest => dest.Vouchers, opt => opt.MapFrom(src => src.OrderVouchers.Select(ov => ov.Voucher)));

            CreateMap<OrderDetailsModelView, OrderDetails>()
                .ForMember(dest => dest.OrderID, opt => opt.Ignore());
            CreateMap<OrderDetails, OrderDetailResponseDTO>()
            .ForMember(dest => dest.UnitPrice, opt => opt.Ignore()); 

            CreateMap<OrderDetails, OrderDetailResponseDTO>();

            // Ánh xạ từ OrderModelView sang Order, nhưng chỉ cập nhật các thuộc tính thay đổi
            CreateMap<OrderModelView, Order>()
                .ForAllMembers(opts => opts.Condition((src, dest, srcMember) => srcMember != null)); // Chỉ ánh xạ khi giá trị mới khác null

            CreateMap<Review, ReviewsModel>().ReverseMap()
                .ForMember(dest => dest.UserID, opt => opt.Ignore()); // Bỏ qua UserID khi map từ ReviewsModel sang Review


            CreateMap<PreOrders, PreOrdersModelView>().ReverseMap()
                .ForMember(dest => dest.UserID, opt => opt.Ignore()); // Bỏ qua UserID khi map từ PreOrdersModelView sang PreOrders
            CreateMap<PreOrders, PreOdersResponseDTO>();

            CreateMap<Voucher, VoucherModelView>().ReverseMap();
            CreateMap<Voucher, VoucherResponseDTO>();
            CreateMap<TransactionHistory, TransactionHistoryResponseDTO>();
        }
    }
}
