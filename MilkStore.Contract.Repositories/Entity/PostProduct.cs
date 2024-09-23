using MilkStore.Core.Base;

namespace MilkStore.Contract.Repositories.Entity
{
    public class PostProduct : BaseEntity
    {
        public string PostId { get; set; }
        public virtual Post Post { get; set; }

        public string ProductId { get; set; }
        public virtual Products Product { get; set; }
    }

}
